import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_CobaltLotusSafe {

    public void runCobaltLotus() throws SQLException {
        String data;
        data = "foo";
        Connection cobaltLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLotus");
        Statement cobaltLotusStatement = null;
        ResultSet cobaltLotusRows = null;
        try {
            cobaltLotusStatement = cobaltLotusConnection.createStatement();
            cobaltLotusRows = cobaltLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltLotusRows.getRow());
        } finally {
            if (cobaltLotusRows != null) {
                cobaltLotusRows.close();
            }
            if (cobaltLotusStatement != null) {
                cobaltLotusStatement.close();
            }
            cobaltLotusConnection.close();
        }
    }
}
