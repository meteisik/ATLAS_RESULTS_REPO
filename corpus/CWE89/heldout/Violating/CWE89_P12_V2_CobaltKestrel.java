import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltKestrel {

    public void runCobaltKestrel() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("COBALT_KESTREL_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltKestrelBase baseObject = new CWE89_P12_V2_CobaltKestrelSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltKestrelBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltKestrelSink extends CWE89_P12_V2_CobaltKestrelBase {
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
