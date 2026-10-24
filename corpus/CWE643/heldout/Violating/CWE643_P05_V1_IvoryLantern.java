import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V1_IvoryLantern {

    private String ivoryLanternData;

    private void sinkIvoryLantern() throws XPathExpressionException {
        String data = ivoryLanternData;
        String ivoryLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            ivoryLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            ivoryLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] ivoryLanternTokens = data.split("||");
            if (ivoryLanternTokens.length < 2) {
                return;
            }
            String ivoryLanternUser = ivoryLanternTokens[0];
            String ivoryLanternPass = ivoryLanternTokens[1];
            XPath ivoryLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource ivoryLanternXml = new InputSource(ivoryLanternXmlFile);
            String ivoryLanternQuery = "//users/user[name/text()='" + ivoryLanternUser
                    + "' and pass/text()='" + ivoryLanternPass + "']" + "/secret/text()";
            String ivoryLanternSecret = (String) ivoryLanternXPath.evaluate(ivoryLanternQuery, ivoryLanternXml, XPathConstants.STRING);
            System.out.println(ivoryLanternSecret);
        }
    }

    public void runIvoryLantern() throws XPathExpressionException {
        String data;
        data = System.getenv("IVORY_LANTERN_ADD");
        ivoryLanternData = data;
        sinkIvoryLantern();
    }
}
