import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AmberCascade {

    public void runAmberCascade() throws SQLException {
        String data;
        data = System.getenv("AMBER_CASCADE_FILTER");
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
