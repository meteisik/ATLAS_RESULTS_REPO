import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VividSundialSafe {

    public void runVividSundial() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VividSundialSafeBase baseObject = new CWE89_P12_V1_VividSundialSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VividSundialSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VividSundialSafeSink extends CWE89_P12_V1_VividSundialSafeBase {
    public void action(String data) throws SQLException {
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        Statement vividSundialStatement = null;
        ResultSet vividSundialRows = null;
        try {
            vividSundialStatement = vividSundialConnection.createStatement();
            vividSundialRows = vividSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividSundialRows.getRow());
        } finally {
            if (vividSundialRows != null) {
                vividSundialRows.close();
            }
            if (vividSundialStatement != null) {
                vividSundialStatement.close();
            }
            vividSundialConnection.close();
        }
    }
}
