import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltLotus {
    private static boolean privateTrue = true;

    public void runCobaltLotus() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("COBALT_LOTUS_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltLotusBase baseObject = new CWE89_P12_V2_CobaltLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltLotusBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltLotusSink extends CWE89_P12_V2_CobaltLotusBase {
    public void action(String data) throws SQLException {
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
