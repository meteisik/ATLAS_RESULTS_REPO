import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltLotusSafe {
    private static boolean privateTrue = true;

    public void runCobaltLotus() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltLotusSafeBase baseObject = new CWE89_P12_V2_CobaltLotusSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltLotusSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltLotusSafeSink extends CWE89_P12_V2_CobaltLotusSafeBase {
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
