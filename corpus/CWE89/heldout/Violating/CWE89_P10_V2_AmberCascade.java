import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberCascade {

    public static String data;

    public void runAmberCascade() throws SQLException {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_CASCADE_FILTER");
        }
        (new CWE89_P10_V2_AmberCascadeSink()).queryAmberCascade();
    }
}

class CWE89_P10_V2_AmberCascadeSink {
    public void queryAmberCascade() throws SQLException {
        String data = CWE89_P10_V2_AmberCascade.data;
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
