import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonRavenSafe {

    public void runCrimsonRaven() throws XPathExpressionException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        CWE643_P12_V2_CrimsonRavenSafeBase baseObject = new CWE643_P12_V2_CrimsonRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonRavenSafeBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonRavenSafeSink extends CWE643_P12_V2_CrimsonRavenSafeBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonRavenXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonRavenXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonRavenXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonRavenTokens = data.split("||");
            if (crimsonRavenTokens.length < 2) {
                return;
            }
            String crimsonRavenUser = crimsonRavenTokens[0];
            String crimsonRavenPass = crimsonRavenTokens[1];
            XPath crimsonRavenXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonRavenXml = new InputSource(crimsonRavenXmlFile);
            String crimsonRavenQuery = "//users/user[name/text()='" + crimsonRavenUser
                    + "' and pass/text()='" + crimsonRavenPass + "']" + "/secret/text()";
            String crimsonRavenSecret = (String) crimsonRavenXPath.evaluate(crimsonRavenQuery, crimsonRavenXml, XPathConstants.STRING);
            System.out.println(crimsonRavenSecret);
        }
    }
}
