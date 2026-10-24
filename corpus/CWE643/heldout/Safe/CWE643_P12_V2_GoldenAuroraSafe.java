import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_GoldenAuroraSafe {

    public void runGoldenAurora() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_GoldenAuroraSafeBase baseObject = new CWE643_P12_V2_GoldenAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_GoldenAuroraSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_GoldenAuroraSafeSink extends CWE643_P12_V2_GoldenAuroraSafeBase {

    public void action(String data) throws XPathExpressionException {
        String goldenAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenAuroraTokens = data.split("||");
            if (goldenAuroraTokens.length < 2) {
                return;
            }
            String goldenAuroraUser = goldenAuroraTokens[0];
            String goldenAuroraPass = goldenAuroraTokens[1];
            XPath goldenAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenAuroraXml = new InputSource(goldenAuroraXmlFile);
            String goldenAuroraQuery = "//users/user[name/text()='" + goldenAuroraUser
                    + "' and pass/text()='" + goldenAuroraPass + "']" + "/secret/text()";
            String goldenAuroraSecret = (String) goldenAuroraXPath.evaluate(goldenAuroraQuery, goldenAuroraXml, XPathConstants.STRING);
            System.out.println(goldenAuroraSecret);
        }
    }
}
