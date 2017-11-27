from setuptools import setup, find_packages


setup(
    name="codecov_forensics",
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=[
        "gidgethub",
        "secretly",
        "treq",
        "Twisted[tls]",
    ],
    entry_points={
        "console_scripts": [
            "which-build = codecov_forensics._impl.main"
        ]
    }
)
