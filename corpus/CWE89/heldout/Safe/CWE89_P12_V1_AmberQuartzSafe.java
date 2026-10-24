import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberQuartzSafe {

    public void runAmberQuartz() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberQuartzSafeBase baseObject = new CWE89_P12_V1_AmberQuartzSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberQuartzSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberQuartzSafeSink extends CWE89_P12_V1_AmberQuartzSafeBase {
    public void action(String data) throws SQLException {
        Connection amberQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberQuartz");
        Statement amberQuartzStatement = null;
        ResultSet amberQuartzRows = null;
        try {
            amberQuartzStatement = amberQuartzConnection.createStatement();
            amberQuartzRows = amberQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberQuartzRows.getRow());
        } finally {
            if (amberQuartzRows != null) {
                amberQuartzRows.close();
            }
            if (amberQuartzStatement != null) {
                amberQuartzStatement.close();
            }
            amberQuartzConnection.close();
        }
    }
}
