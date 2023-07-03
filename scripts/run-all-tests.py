import os
import subprocess
import xml.etree.ElementTree as ET

def generate_junit_xml(results, output_file):

    # Count the number of failed tests
    failures = len([r for r in results if not r[1]])

    # Create the root 'testsuite' element
    root = ET.Element("testsuite", name="network-scanner-cmd-tests", tests="%d"%len(results), failures="%d"%failures, errors="0")

    for result in results:
        # Create a 'testcase' element
        testcase = ET.SubElement(root, "testcase", classname="test-app-discovery.sh", name=result[0])

        if not result[1]:
            # Create a 'failure' element
            failure = ET.SubElement(testcase, "failure", message='Test failed')
            # Set the text of the 'failure' element with CDATA
            failure.text = result[2]

    # Create the XML string
    xml_str = ET.tostring(root, encoding='utf-8')

    # Write the XML to a file
    with open(output_file, 'wb') as f:
        f.write(xml_str)


# Go to test directory
os.chdir("tests")

# Run all tests

# List all application tests (all direcrories that are under apps directory)
app_tests = [d for d in os.listdir("apps") if os.path.isdir(os.path.join("apps", d))]

results = []
# Run all application tests
for app_test in app_tests:
    # Call the test-app-discovery.sh script, capture the output and return code using subprocess.check_output
    # and save output to a variable
    
    try:
        p = subprocess.run(["./test-app-discovery.sh", app_test],check=True, stderr=subprocess.PIPE)
        stderr = ""
        result = True
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode("utf-8")
        result = False

    # Save the output to a list
    results.append((app_test, result, stderr))

# Check if all results are True
all_results = [r[1] for r in results]
if all(all_results):
    print("All tests passed")
else:
    print("Some tests failed")
    for r in results:
        if not r[1]:
            print("Test {} failed with error: {}".format(r[0], r[2]))

# Create Junit XML report from results list
generate_junit_xml(results, "test-results.xml")

# Go back to the original directory
os.chdir("..")


