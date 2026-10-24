import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltKestrelSafe {

    public void runCobaltKestrel() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltKestrelSafeBase baseObject = new CWE89_P12_V2_CobaltKestrelSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltKestrelSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltKestrelSafeSink extends CWE89_P12_V2_CobaltKestrelSafeBase {
    public void action(String data) throws SQLException {
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
