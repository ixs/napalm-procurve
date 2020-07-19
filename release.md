Release procedure
=================

1. Increase version in setup.py and commit
2. Make sure the napalm-community tree is known to local git:
   `git remote add community git@github.com:napalm-automation-community/napalm-hp-procurve.git`
3. Push to github:
   `git push origin`
   `git push community`
4. Tag the release with the value of version: `git tag <version>`
5. Push those tags to github: `git push origin --tags`
6. Push copy to the napalm-automation copy:
   `git push community --tags`
7. Generate bdist_wheel archives: `python3 setup.py sdist bdist_wheel
8. Upload to pypi: `python3 -m twine upload dist/*`
