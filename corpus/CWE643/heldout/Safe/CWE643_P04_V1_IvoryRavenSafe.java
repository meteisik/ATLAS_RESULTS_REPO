import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V1_IvoryRavenSafe {

    private String sourceIvoryRaven() {
        String data;
        data = "foo";
        return data;
    }

    public void runIvoryRaven() throws XPathExpressionException {
        String data = sourceIvoryRaven();
        String ivoryRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryRavenTokens = data.split("||");
            if (ivoryRavenTokens.length < 2) {
                return;
            }
            String ivoryRavenUser = ivoryRavenTokens[0];
            String ivoryRavenPass = ivoryRavenTokens[1];
            XPath ivoryRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryRavenXml = new InputSource(ivoryRavenXmlFile);
            String ivoryRavenQuery = "//users/user[name/text()='" + ivoryRavenUser
                    + "' and pass/text()='" + ivoryRavenPass + "']" + "/secret/text()";
            String ivoryRavenSecret = (String) ivoryRavenXPath.evaluate(ivoryRavenQuery, ivoryRavenXml, XPathConstants.STRING);
            System.out.println(ivoryRavenSecret);
        }
    }
}
