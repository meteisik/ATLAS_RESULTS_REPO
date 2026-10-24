import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberCascadeSafe {

    public void runAmberCascade() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberCascadeSafeBase baseObject = new CWE89_P12_V1_AmberCascadeSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberCascadeSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberCascadeSafeSink extends CWE89_P12_V1_AmberCascadeSafeBase {
    public void action(String data) throws SQLException {
        Connection amberCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCascade");
        Statement amberCascadeStatement = null;
        ResultSet amberCascadeRows = null;
        try {
            amberCascadeStatement = amberCascadeConnection.createStatement();
            amberCascadeRows = amberCascadeStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberCascadeRows.getRow());
        } finally {
            if (amberCascadeRows != null) {
                amberCascadeRows.close();
            }
            if (amberCascadeStatement != null) {
                amberCascadeStatement.close();
            }
            amberCascadeConnection.close();
        }
    }
}
