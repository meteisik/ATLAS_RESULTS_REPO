import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VividAurora {

    public void runVividAurora() throws XPathExpressionException {
        String data;
        data = System.getenv("VIVID_AURORA_ADD");
        CWE643_P12_V1_VividAuroraBase baseObject = new CWE643_P12_V1_VividAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VividAuroraBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VividAuroraSink extends CWE643_P12_V1_VividAuroraBase {

    public void action(String data) throws XPathExpressionException {
        String vividAuroraXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            vividAuroraXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            vividAuroraXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] vividAuroraTokens = data.split("||");
            if (vividAuroraTokens.length < 2) {
                return;
            }
            String vividAuroraUser = vividAuroraTokens[0];
            String vividAuroraPass = vividAuroraTokens[1];
            XPath vividAuroraXPath = XPathFactory.newInstance().newXPath();
            InputSource vividAuroraXml = new InputSource(vividAuroraXmlFile);
            String vividAuroraQuery = "//users/user[name/text()='" + vividAuroraUser
                    + "' and pass/text()='" + vividAuroraPass + "']" + "/secret/text()";
            String vividAuroraSecret = (String) vividAuroraXPath.evaluate(vividAuroraQuery, vividAuroraXml, XPathConstants.STRING);
            System.out.println(vividAuroraSecret);
        }
    }
}
