import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CobaltLotus {

    public void runCobaltLotus() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_LOTUS_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
