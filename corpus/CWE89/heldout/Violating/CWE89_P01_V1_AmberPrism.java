import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AmberPrism {

    public void runAmberPrism() throws SQLException {
        String data;
        data = System.getenv("AMBER_PRISM_FILTER");
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
