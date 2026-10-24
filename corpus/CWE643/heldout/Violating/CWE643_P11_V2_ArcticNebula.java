import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_ArcticNebula {

    public void runArcticNebula() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_NEBULA_ADD");
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_ArcticNebulaSink()).sinkArcticNebula(dataHashMap);
    }
}

class CWE643_P11_V2_ArcticNebulaSink {

    public void sinkArcticNebula(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String arcticNebulaXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            arcticNebulaXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            arcticNebulaXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] arcticNebulaTokens = data.split("||");
            if (arcticNebulaTokens.length < 2) {
                return;
            }
            String arcticNebulaUser = arcticNebulaTokens[0];
            String arcticNebulaPass = arcticNebulaTokens[1];
            XPath arcticNebulaXPath = XPathFactory.newInstance().newXPath();
            InputSource arcticNebulaXml = new InputSource(arcticNebulaXmlFile);
            String arcticNebulaQuery = "//users/user[name/text()='" + arcticNebulaUser
                    + "' and pass/text()='" + arcticNebulaPass + "']" + "/secret/text()";
            String arcticNebulaSecret = (String) arcticNebulaXPath.evaluate(arcticNebulaQuery, arcticNebulaXml, XPathConstants.STRING);
            System.out.println(arcticNebulaSecret);
        }
    }
}
