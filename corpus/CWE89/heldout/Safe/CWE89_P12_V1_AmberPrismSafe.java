import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberPrismSafe {

    public void runAmberPrism() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberPrismSafeBase baseObject = new CWE89_P12_V1_AmberPrismSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberPrismSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberPrismSafeSink extends CWE89_P12_V1_AmberPrismSafeBase {
    public void action(String data) throws SQLException {
        Connection amberPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberPrism");
        Statement amberPrismStatement = null;
        ResultSet amberPrismRows = null;
        try {
            amberPrismStatement = amberPrismConnection.createStatement();
            amberPrismRows = amberPrismStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberPrismRows.getRow());
        } finally {
            if (amberPrismRows != null) {
                amberPrismRows.close();
            }
            if (amberPrismStatement != null) {
                amberPrismStatement.close();
            }
            amberPrismConnection.close();
        }
    }
}
