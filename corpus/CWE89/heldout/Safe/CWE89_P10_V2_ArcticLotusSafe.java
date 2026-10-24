import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticLotusSafe {

    public static String data;

    public void runArcticLotus() throws SQLException {
        while (true) {
            data = "foo";
            break;
        }
        (new CWE89_P10_V2_ArcticLotusSafeSink()).queryArcticLotus();
    }
}

class CWE89_P10_V2_ArcticLotusSafeSink {
    public void queryArcticLotus() throws SQLException {
        String data = CWE89_P10_V2_ArcticLotusSafe.data;
        Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
        Statement arcticLotusStatement = null;
        ResultSet arcticLotusRows = null;
        try {
            arcticLotusStatement = arcticLotusConnection.createStatement();
            arcticLotusRows = arcticLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticLotusRows.getRow());
        } finally {
            if (arcticLotusRows != null) {
                arcticLotusRows.close();
            }
            if (arcticLotusStatement != null) {
                arcticLotusStatement.close();
            }
            arcticLotusConnection.close();
        }
    }
}
