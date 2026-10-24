import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberCascadeSafe {

    public static String data;

    public void runAmberCascade() throws SQLException {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        (new CWE89_P10_V2_AmberCascadeSafeSink()).queryAmberCascade();
    }
}

class CWE89_P10_V2_AmberCascadeSafeSink {
    public void queryAmberCascade() throws SQLException {
        String data = CWE89_P10_V2_AmberCascadeSafe.data;
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
