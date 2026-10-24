import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_CobaltLantern {

    public void runCobaltLantern() throws SQLException {
        String data;
        data = System.getenv("COBALT_LANTERN_FILTER");
        Connection cobaltLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLantern");
        Statement cobaltLanternStatement = null;
        ResultSet cobaltLanternRows = null;
        try {
            cobaltLanternStatement = cobaltLanternConnection.createStatement();
            cobaltLanternRows = cobaltLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltLanternRows.getRow());
        } finally {
            if (cobaltLanternRows != null) {
                cobaltLanternRows.close();
            }
            if (cobaltLanternStatement != null) {
                cobaltLanternStatement.close();
            }
            cobaltLanternConnection.close();
        }
    }
}
