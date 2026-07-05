# eval/stats.py
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def compute_mcnemar_test():
    pass

def compute_bootstrap_ci():
    pass

def main():
    logger.info("Computing statistical significance...")
    # TODO: Calculate McNemar's test and bootstrap CIs on the generated results

if __name__ == "__main__":
    main()
