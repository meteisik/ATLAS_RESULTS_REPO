import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_CrimsonKestrelSafe {

    public void runCrimsonKestrel() throws XPathExpressionException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        String crimsonKestrelXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonKestrelXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonKestrelXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonKestrelTokens = data.split("||");
            if (crimsonKestrelTokens.length < 2) {
                return;
            }
            String crimsonKestrelUser = crimsonKestrelTokens[0];
            String crimsonKestrelPass = crimsonKestrelTokens[1];
            XPath crimsonKestrelXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonKestrelXml = new InputSource(crimsonKestrelXmlFile);
            String crimsonKestrelQuery = "//users/user[name/text()='" + crimsonKestrelUser
                    + "' and pass/text()='" + crimsonKestrelPass + "']" + "/secret/text()";
            String crimsonKestrelSecret = (String) crimsonKestrelXPath.evaluate(crimsonKestrelQuery, crimsonKestrelXml, XPathConstants.STRING);
            System.out.println(crimsonKestrelSecret);
        }
    }
}
