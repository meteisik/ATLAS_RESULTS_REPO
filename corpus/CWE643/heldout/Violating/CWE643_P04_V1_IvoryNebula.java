import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V1_IvoryNebula {

    private String sourceIvoryNebula() {
        String data;
        data = System.getenv("IVORY_NEBULA_ADD");
        return data;
    }

    public void runIvoryNebula() throws XPathExpressionException {
        String data = sourceIvoryNebula();
        String ivoryNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryNebulaTokens = data.split("||");
            if (ivoryNebulaTokens.length < 2) {
                return;
            }
            String ivoryNebulaUser = ivoryNebulaTokens[0];
            String ivoryNebulaPass = ivoryNebulaTokens[1];
            XPath ivoryNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryNebulaXml = new InputSource(ivoryNebulaXmlFile);
            String ivoryNebulaQuery = "//users/user[name/text()='" + ivoryNebulaUser
                    + "' and pass/text()='" + ivoryNebulaPass + "']" + "/secret/text()";
            String ivoryNebulaSecret = (String) ivoryNebulaXPath.evaluate(ivoryNebulaQuery, ivoryNebulaXml, XPathConstants.STRING);
            System.out.println(ivoryNebulaSecret);
        }
    }
}
