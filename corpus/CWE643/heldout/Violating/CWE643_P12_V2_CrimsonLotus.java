import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonLotus {

    public void runCrimsonLotus() throws XPathExpressionException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("CRIMSON_LOTUS_ADD");
            break;
        default:
            data = null;
            break;
        }
        CWE643_P12_V2_CrimsonLotusBase baseObject = new CWE643_P12_V2_CrimsonLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonLotusBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonLotusSink extends CWE643_P12_V2_CrimsonLotusBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonLotusTokens = data.split("||");
            if (crimsonLotusTokens.length < 2) {
                return;
            }
            String crimsonLotusUser = crimsonLotusTokens[0];
            String crimsonLotusPass = crimsonLotusTokens[1];
            XPath crimsonLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonLotusXml = new InputSource(crimsonLotusXmlFile);
            String crimsonLotusQuery = "//users/user[name/text()='" + crimsonLotusUser
                    + "' and pass/text()='" + crimsonLotusPass + "']" + "/secret/text()";
            String crimsonLotusSecret = (String) crimsonLotusXPath.evaluate(crimsonLotusQuery, crimsonLotusXml, XPathConstants.STRING);
            System.out.println(crimsonLotusSecret);
        }
    }
}
