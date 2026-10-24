import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_SaffronMantisSafe {

    public void runSaffronMantis() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = (new CWE643_P07_V2_SaffronMantisSafeSource()).sourceSaffronMantis();
            break;
        default:
            data = null;
            break;
        }
        String saffronMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronMantisTokens = data.split("||");
            if (saffronMantisTokens.length < 2) {
                return;
            }
            String saffronMantisUser = saffronMantisTokens[0];
            String saffronMantisPass = saffronMantisTokens[1];
            XPath saffronMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronMantisXml = new InputSource(saffronMantisXmlFile);
            String saffronMantisQuery = "//users/user[name/text()='" + saffronMantisUser
                    + "' and pass/text()='" + saffronMantisPass + "']" + "/secret/text()";
            String saffronMantisSecret = (String) saffronMantisXPath.evaluate(saffronMantisQuery, saffronMantisXml, XPathConstants.STRING);
            System.out.println(saffronMantisSecret);
        }
    }
}

class CWE643_P07_V2_SaffronMantisSafeSource {

    public String sourceSaffronMantis() {
        String data;
        data = "foo";
        return data;
    }
}
