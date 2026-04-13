
# Running VulnTrain on an HPC cluster

This page provides a reference configuration for running VulnTrain on a
[EuroHPC-style](https://www.eurohpc-ju.europa.eu) GPU cluster managed by SLURM.
Treat it as a template and adapt the account, partition, and resource requests
to match your local system.

High-level workflow:

1. Create a shared Conda environment.
2. Test the installation on the login node.
3. Submit a SLURM job that launches distributed training.

## 1. Shared Conda environment

Run the following once on a **login node** to create a reusable environment for
VulnTrain. If your site provides Conda/Miniconda via environment modules, load
the relevant module first.

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
activated from both login and **compute nodes**.

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

## 3. Example SLURM scripts

Save one of the scripts below as `run_vulntrain.slurm` (or a similar name) in
your working directory. Adjust `--account`, `--partition`, time, memory, and
GPU counts to match your project and cluster policies.

### Single-node configuration using `torchrun`

```bash
#!/bin/bash
#SBATCH --job-name=vulntrain
#SBATCH --account=<-your-account-id->
#SBATCH --partition=gpu
#SBATCH --nodes=1
#SBATCH --ntasks=4
#SBATCH --gpus-per-node=4
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=10:00:00
#SBATCH --output=logs/vulntrain_%j.out
#SBATCH --error=logs/vulntrain_%j.err
#SBATCH --qos=default

set -e

source $HOME/miniconda3/etc/profile.d/conda.sh
conda activate $HOME/conda_envs/vulntrain

# --------------------------
# Parameters for the trainer
# --------------------------
BASE_MODEL=roberta-base
DATASET_ID=CIRCL/vulnerability-scores
RESULT_REPO_ID=CIRCL/vulnerability-severity-classification-roberta-base
RESULT_SAVE_DIR=$HOME/models/vulntrain_roberta


# --------------------------
# NCCL configuration
# --------------------------
export NCCL_DEBUG=INFO
export NCCL_IB_DISABLE=1
export NCCL_P2P_LEVEL=NVL

export OMP_NUM_THREADS=$SLURM_CPUS_PER_TASK
export MASTER_ADDR=$(hostname)

# Optional but recommended
export HF_HOME=${SLURM_TMPDIR:-$HOME}/hf_cache
mkdir -p $HF_HOME

torchrun --nproc_per_node=$SLURM_NTASKS \
         --master_port=29500 \
         $HOME/conda_envs/vulntrain/bin/vulntrain-train-severity-classification \
            --base-model $BASE_MODEL \
            --dataset-id $DATASET_ID \
            --repo-id $RESULT_REPO_ID \
            --model-save-dir $RESULT_SAVE_DIR \
            --no-push \
            --no-cache
```


### Example of multi-node configuration

{{< callout type="warning" >}}
  The multi-node configuration is less reliable and has caused various issues in practice (NCCL timeouts, rank synchronization failures, inconsistent checkpoint saving across nodes). The single-node configuration above works well and is recommended unless you specifically need to scale beyond the GPUs available on a single node.
{{< /callout >}}

```bash
#!/bin/bash
#SBATCH --job-name=vulntrain
#SBATCH --account=<-your-account-id->
#SBATCH --partition=gpu
#SBATCH --nodes=4
#SBATCH --ntasks-per-node=4
#SBATCH --gpus-per-node=4
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=10:00:00
#SBATCH --output=logs/vulntrain_%j_%N.out
#SBATCH --error=logs/vulntrain_%j_%N.err
#SBATCH --qos=default

set -e

# -------------------------------
# Activate Conda environment
# -------------------------------
source $HOME/miniconda3/etc/profile.d/conda.sh
conda activate $HOME/conda_envs/vulntrain

# --------------------------
# Parameters for the trainer
# --------------------------
BASE_MODEL=roberta-base
DATASET_ID=CIRCL/vulnerability-scores
RESULT_REPO_ID=CIRCL/vulnerability-severity-classification-roberta-base
RESULT_SAVE_DIR=$HOME/models/vulntrain_roberta

# --------------------------
# NCCL configuration
# --------------------------
export NCCL_DEBUG=INFO
export NCCL_IB_DISABLE=1        # if no InfiniBand, keep it disabled
export NCCL_P2P_LEVEL=NODE      # change from NVL to NODE for multi-node

export OMP_NUM_THREADS=$SLURM_CPUS_PER_TASK

# Optional but recommended
export HF_HOME=${SLURM_TMPDIR:-$HOME}/hf_cache
mkdir -p $HF_HOME

torchrun --nnodes=$SLURM_JOB_NUM_NODES \
         --nproc_per_node=$SLURM_NTASKS_PER_NODE \
         --node_rank=$SLURM_NODEID \
         --master_addr=$(scontrol show hostnames $SLURM_JOB_NODELIST | head -n 1) \
         --master_port=29500 \
         $HOME/conda_envs/vulntrain/bin/vulntrain-train-severity-classification \
            --base-model $BASE_MODEL \
            --dataset-id $DATASET_ID \
            --repo-id $RESULT_REPO_ID \
            --model-save-dir $RESULT_SAVE_DIR \
            --no-cache \
            --no-push
```



## 4. Submit and monitor the job

Submit the job from the directory where `run_vulntrain.slurm` is stored:

```bash
sbatch run_vulntrain.slurm
```

To follow progress, use your cluster’s standard tools, for example:

- `squeue -u $USER` to see queued and running jobs.
- `tail -f vulntrain-<jobid>.out` to stream the job’s output log.


Display accounting data and job steps in the Slurm job accounting log or Slurm database:

```bash
sacct -j <-jobid-> --format=JobID,JobName,Partition,AllocTRES,State,Elapsed,TotalCPU
```