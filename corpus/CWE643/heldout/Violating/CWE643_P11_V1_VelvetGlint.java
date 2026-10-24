import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_VelvetGlint {

    public void runVelvetGlint() throws XPathExpressionException {
        String data;
        data = System.getenv("VELVET_GLINT_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_VelvetGlintSink()).sinkVelvetGlint(dataHashMap);
    }
}

class CWE643_P11_V1_VelvetGlintSink {

    public void sinkVelvetGlint(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String velvetGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetGlintTokens = data.split("||");
            if (velvetGlintTokens.length < 2) {
                return;
            }
            String velvetGlintUser = velvetGlintTokens[0];
            String velvetGlintPass = velvetGlintTokens[1];
            XPath velvetGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetGlintXml = new InputSource(velvetGlintXmlFile);
            String velvetGlintQuery = "//users/user[name/text()='" + velvetGlintUser
                    + "' and pass/text()='" + velvetGlintPass + "']" + "/secret/text()";
            String velvetGlintSecret = (String) velvetGlintXPath.evaluate(velvetGlintQuery, velvetGlintXml, XPathConstants.STRING);
            System.out.println(velvetGlintSecret);
        }
    }
}
