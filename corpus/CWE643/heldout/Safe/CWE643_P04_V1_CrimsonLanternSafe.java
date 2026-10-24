import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V1_CrimsonLanternSafe {

    private String sourceCrimsonLantern() {
        String data;
        data = "foo";
        return data;
    }

    public void runCrimsonLantern() throws XPathExpressionException {
        String data = sourceCrimsonLantern();
        String crimsonLanternXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonLanternXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonLanternXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonLanternTokens = data.split("||");
            if (crimsonLanternTokens.length < 2) {
                return;
            }
            String crimsonLanternUser = crimsonLanternTokens[0];
            String crimsonLanternPass = crimsonLanternTokens[1];
            XPath crimsonLanternXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonLanternXml = new InputSource(crimsonLanternXmlFile);
            String crimsonLanternQuery = "//users/user[name/text()='" + crimsonLanternUser
                    + "' and pass/text()='" + crimsonLanternPass + "']" + "/secret/text()";
            String crimsonLanternSecret = (String) crimsonLanternXPath.evaluate(crimsonLanternQuery, crimsonLanternXml, XPathConstants.STRING);
            System.out.println(crimsonLanternSecret);
        }
    }
}
