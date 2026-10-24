import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberSundialSafe {

    public void runAmberSundial() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberSundialSafeBase baseObject = new CWE89_P12_V1_AmberSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberSundialSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberSundialSafeSink extends CWE89_P12_V1_AmberSundialSafeBase {
    public void action(String data) throws SQLException {
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        Statement amberSundialStatement = null;
        ResultSet amberSundialRows = null;
        try {
            amberSundialStatement = amberSundialConnection.createStatement();
            amberSundialRows = amberSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberSundialRows.getRow());
        } finally {
            if (amberSundialRows != null) {
                amberSundialRows.close();
            }
            if (amberSundialStatement != null) {
                amberSundialStatement.close();
            }
            amberSundialConnection.close();
        }
    }
}
