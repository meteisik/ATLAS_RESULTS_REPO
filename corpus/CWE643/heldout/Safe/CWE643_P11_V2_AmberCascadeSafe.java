import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V2_AmberCascadeSafe {

    public void runAmberCascade() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V2_AmberCascadeSafeSink()).sinkAmberCascade(dataHashMap);
    }
}

class CWE643_P11_V2_AmberCascadeSafeSink {

    public void sinkAmberCascade(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String amberCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberCascadeTokens = data.split("||");
            if (amberCascadeTokens.length < 2) {
                return;
            }
            String amberCascadeUser = amberCascadeTokens[0];
            String amberCascadePass = amberCascadeTokens[1];
            XPath amberCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource amberCascadeXml = new InputSource(amberCascadeXmlFile);
            String amberCascadeQuery = "//users/user[name/text()='" + amberCascadeUser
                    + "' and pass/text()='" + amberCascadePass + "']" + "/secret/text()";
            String amberCascadeSecret = (String) amberCascadeXPath.evaluate(amberCascadeQuery, amberCascadeXml, XPathConstants.STRING);
            System.out.println(amberCascadeSecret);
        }
    }
}
