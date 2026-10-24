import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonLotus {

    public void runCrimsonLotus() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("CRIMSON_LOTUS_FILTER");
            break;
        default:
            data = null;
            break;
        }
        CWE89_P12_V2_CrimsonLotusBase baseObject = new CWE89_P12_V2_CrimsonLotusSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonLotusBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonLotusSink extends CWE89_P12_V2_CrimsonLotusBase {
    public void action(String data) throws SQLException {
        Connection crimsonLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLotus");
        Statement crimsonLotusStatement = null;
        ResultSet crimsonLotusRows = null;
        try {
            crimsonLotusStatement = crimsonLotusConnection.createStatement();
            crimsonLotusRows = crimsonLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonLotusRows.getRow());
        } finally {
            if (crimsonLotusRows != null) {
                crimsonLotusRows.close();
            }
            if (crimsonLotusStatement != null) {
                crimsonLotusStatement.close();
            }
            crimsonLotusConnection.close();
        }
    }
}
