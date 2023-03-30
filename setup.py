from setuptools import find_packages, setup

setup(
    name='netbox-secrets',
    version='1.8.0',
    description='Netbox Secrets',
    long_description='A Secret store for NetBox',
    url='https://github.com/Onemind-Services-LLC/netbox-secrets/',
    author='Abhimanyu Saharan',
    author_email='asaharan@onemindservices.com',
    license='Apache 2.0',
    install_requires=[
        'pycryptodome',
    ],
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    zip_safe=False,
)
