import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_CrimsonOrbit {

    public void runCrimsonOrbit() throws XPathExpressionException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("CRIMSON_ORBIT_ADD");
        }
        CWE643_P12_V2_CrimsonOrbitBase baseObject = new CWE643_P12_V2_CrimsonOrbitSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_CrimsonOrbitBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_CrimsonOrbitSink extends CWE643_P12_V2_CrimsonOrbitBase {

    public void action(String data) throws XPathExpressionException {
        String crimsonOrbitXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            crimsonOrbitXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            crimsonOrbitXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] crimsonOrbitTokens = data.split("||");
            if (crimsonOrbitTokens.length < 2) {
                return;
            }
            String crimsonOrbitUser = crimsonOrbitTokens[0];
            String crimsonOrbitPass = crimsonOrbitTokens[1];
            XPath crimsonOrbitXPath = XPathFactory.newInstance().newXPath();
            InputSource crimsonOrbitXml = new InputSource(crimsonOrbitXmlFile);
            String crimsonOrbitQuery = "//users/user[name/text()='" + crimsonOrbitUser
                    + "' and pass/text()='" + crimsonOrbitPass + "']" + "/secret/text()";
            String crimsonOrbitSecret = (String) crimsonOrbitXPath.evaluate(crimsonOrbitQuery, crimsonOrbitXml, XPathConstants.STRING);
            System.out.println(crimsonOrbitSecret);
        }
    }
}
