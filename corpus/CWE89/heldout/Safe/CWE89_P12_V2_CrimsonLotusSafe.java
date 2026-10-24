import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonLotusSafe {

    public void runCrimsonLotus() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        CWE89_P12_V2_CrimsonLotusSafeBase baseObject = new CWE89_P12_V2_CrimsonLotusSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonLotusSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonLotusSafeSink extends CWE89_P12_V2_CrimsonLotusSafeBase {
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
