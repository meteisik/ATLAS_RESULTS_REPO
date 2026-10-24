import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VividPrismSafe {

    public void runVividPrism() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VividPrismSafeBase baseObject = new CWE89_P12_V1_VividPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VividPrismSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VividPrismSafeSink extends CWE89_P12_V1_VividPrismSafeBase {
    public void action(String data) throws SQLException {
        Connection vividPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividPrism");
        Statement vividPrismStatement = null;
        ResultSet vividPrismRows = null;
        try {
            vividPrismStatement = vividPrismConnection.createStatement();
            vividPrismRows = vividPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividPrismRows.getRow());
        } finally {
            if (vividPrismRows != null) {
                vividPrismRows.close();
            }
            if (vividPrismStatement != null) {
                vividPrismStatement.close();
            }
            vividPrismConnection.close();
        }
    }
}
