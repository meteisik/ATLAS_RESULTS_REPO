import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_CobaltKestrel {

    public void runCobaltKestrel() throws SQLException {
        String data;
        data = System.getenv("COBALT_KESTREL_FILTER");
        Connection cobaltKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltKestrel");
        Statement cobaltKestrelStatement = null;
        ResultSet cobaltKestrelRows = null;
        try {
            cobaltKestrelStatement = cobaltKestrelConnection.createStatement();
            cobaltKestrelRows = cobaltKestrelStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltKestrelRows.getRow());
        } finally {
            if (cobaltKestrelRows != null) {
                cobaltKestrelRows.close();
            }
            if (cobaltKestrelStatement != null) {
                cobaltKestrelStatement.close();
            }
            cobaltKestrelConnection.close();
        }
    }
}
