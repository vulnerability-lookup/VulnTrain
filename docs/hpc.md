
# Running VulnTrain on an HPC cluster

This page shows a reference configuration for running VulnTrain on a EuroHPC-style
GPU cluster managed by SLURM. Treat this as a template and adapt the account,
partition, and resource requests to match your local system.

The workflow is:

1. Create a shared Conda environment.
2. Test the installation on the login node.
3. Submit a SLURM job that launches distributed training.

## 1. Shared Conda environment

Run the following once on a login node to create a reusable environment for
VulnTrain. If your site provides a module for Conda or Miniconda, make sure it
is loaded first.

```bash
# 1. Make a folder for shared environments if it doesn't exist
mkdir -p $HOME/conda_envs

# 2. Create a Conda environment with Python 3.11
conda create -y -p $HOME/conda_envs/vulntrain python=3.11

# 3. Activate the environment
conda activate $HOME/conda_envs/vulntrain

# 4. Upgrade pip
pip install --upgrade pip

# 5. Install vulntrain and dependencies
pip install vulntrain datasets transformers accelerate
```

This creates an environment at `$HOME/conda_envs/vulntrain` that can be
activated from both login and compute nodes.

## 2. Test the environment on the login node

Before requesting GPUs, quickly verify that Python and the VulnTrain CLI are
available in the environment:

```bash
# Activate environment
conda activate $HOME/conda_envs/vulntrain

# Check Python version
python --version

# Check vulntrain CLI
vulntrain-train-severity-classification --help
```

If these commands run without errors, you are ready to submit a job.

## 3. Example SLURM script

Save the script below as `run_vulntrain.slurm` (or a similar name) in your
working directory. Adjust `--account`, `--partition`, time, memory, and GPU
counts to match your project and cluster policies.

```bash
#!/bin/bash
#SBATCH --job-name=vulntrain
#SBATCH --output=vulntrain-%j.out
#SBATCH --error=vulntrain-%j.err
#SBATCH --account=p201224
#SBATCH --partition=gpu
#SBATCH --nodes=1
#SBATCH --ntasks=4          # one task per GPU
#SBATCH --gpus-per-node=4   # allocate all 4 GPUs on the node
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=06:00:00
#SBATCH --qos=default

# -------------------------------
# Distributed training variables
# -------------------------------
export MASTER_ADDR=$(scontrol show hostname $SLURM_NODELIST | head -n 1)
export MASTER_PORT=29500
export WORLD_SIZE=$SLURM_NTASKS

# -------------------------------
# Activate Conda environment
# -------------------------------
source $HOME/miniconda3/etc/profile.d/conda.sh
conda activate $HOME/conda_envs/vulntrain

# -------------------------------
# Performance & stability settings
# -------------------------------

# Disable CodeCarbon for multi-GPU runs (prevents file collisions)
export CODECARBON_OFF=1

# Avoid tokenizer parallelism issues
export TOKENIZERS_PARALLELISM=false

# -------------------------------
# HuggingFace cache directories
# -------------------------------
# Use node-local scratch if available, otherwise fallback to home
export HF_HOME=${SLURM_TMPDIR:-$HOME}/hf_cache_$SLURM_PROCID
export TRANSFORMERS_CACHE=$HF_HOME/transformers
export DATASETS_CACHE=$HF_HOME/datasets
mkdir -p $HF_HOME

# Optional: improve NCCL stability on some clusters
export NCCL_DEBUG=WARN
export NCCL_IB_DISABLE=0

# Show assigned GPUs
echo "CUDA_VISIBLE_DEVICES=$CUDA_VISIBLE_DEVICES"
nvidia-smi

# -------------------------------
# Launch Distributed Training
# -------------------------------
srun --ntasks=$SLURM_NTASKS \
     --cpus-per-task=$SLURM_CPUS_PER_TASK \
     --gpus-per-task=1 \
     --export=ALL \
     bash -c '
export RANK=$SLURM_PROCID
export LOCAL_RANK=$SLURM_LOCALID
export CODECARBON_OFF=1

$HOME/conda_envs/vulntrain/bin/vulntrain-train-severity-classification \
        --base-model roberta-base \
        --dataset-id CIRCL/vulnerability-scores \
        --repo-id cedricbonhomme/vulnerability-severity-classification-roberta-base
' 
```

Key points:

- The job requests 1 node with 4 GPUs and 4 tasks (one per GPU).
- `WORLD_SIZE` is set from `SLURM_NTASKS` for distributed training.
- Separate HuggingFace cache directories are used per task to avoid I/O
    contention on shared filesystems.

## 4. Submit and monitor the job

Submit the job from the directory where `run_vulntrain.slurm` is stored:

```bash
sbatch run_vulntrain.slurm
```

To follow progress, use your cluster's standard tools, for example:

- `squeue -u $USER` to see queued and running jobs.
- `tail -f vulntrain-<jobid>.out` to stream the job's output log.