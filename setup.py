from setuptools import find_packages, setup

setup(
    name="privacy-review-agent",
    version="0.1.0",
    description="Autonomous PII/sensitive-data review agent for PRs",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    install_requires=["click>=8.1.7", "PyYAML>=6.0.1"],
    extras_require={
        "dev": ["pytest>=8.2.0", "ruff>=0.5.0"],
        "semgrep": ["semgrep>=1.185.0"],
    },
    entry_points={"console_scripts": ["privacy-review-agent=privacy_review_agent.cli:main"]},
)
