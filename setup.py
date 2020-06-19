from setuptools import setup, find_packages
package_name = 'django3-auth-saml2'
package_version = open('VERSION').read().strip()


def requirements(filename='requirements.txt'):
    return open(filename.strip()).readlines()


with open("README.md", "r") as fh:
    long_description = fh.read()


setup(
    name=package_name,
    version=package_version,
    description='Django3 auth SAML2 integration',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Jeremy Schulman',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements(),
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: Apache Software License',
        'Framework :: Django :: 3.0',
        'Programming Language :: Python :: 3.6',
    ]
)
