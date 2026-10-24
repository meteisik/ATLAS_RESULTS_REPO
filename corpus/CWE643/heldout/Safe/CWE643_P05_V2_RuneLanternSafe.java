import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_RuneLanternSafe {

    private String runeLanternData;

    private void sinkRuneLantern() throws XPathExpressionException {
        String data = runeLanternData;
        String runeLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            runeLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            runeLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] runeLanternTokens = data.split("||");
            if (runeLanternTokens.length < 2) {
                return;
            }
            String runeLanternUser = runeLanternTokens[0];
            String runeLanternPass = runeLanternTokens[1];
            XPath runeLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource runeLanternXml = new InputSource(runeLanternXmlFile);
            String runeLanternQuery = "//users/user[name/text()='" + runeLanternUser
                    + "' and pass/text()='" + runeLanternPass + "']" + "/secret/text()";
            String runeLanternSecret = (String) runeLanternXPath.evaluate(runeLanternQuery, runeLanternXml, XPathConstants.STRING);
            System.out.println(runeLanternSecret);
        }
    }

    public void runRuneLantern() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        runeLanternData = data;
        sinkRuneLantern();
    }
}
