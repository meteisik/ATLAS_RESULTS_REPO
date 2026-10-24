import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberSundial {

    public void runAmberSundial() throws SQLException {
        String data;
        data = System.getenv("AMBER_SUNDIAL_FILTER");
        CWE89_P12_V1_AmberSundialBase baseObject = new CWE89_P12_V1_AmberSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberSundialBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberSundialSink extends CWE89_P12_V1_AmberSundialBase {
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
