import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberMantisSafe {

    public void runAmberMantis() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberMantisSafeBase baseObject = new CWE89_P12_V1_AmberMantisSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberMantisSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberMantisSafeSink extends CWE89_P12_V1_AmberMantisSafeBase {
    public void action(String data) throws SQLException {
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        Statement amberMantisStatement = null;
        ResultSet amberMantisRows = null;
        try {
            amberMantisStatement = amberMantisConnection.createStatement();
            amberMantisRows = amberMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberMantisRows.getRow());
        } finally {
            if (amberMantisRows != null) {
                amberMantisRows.close();
            }
            if (amberMantisStatement != null) {
                amberMantisStatement.close();
            }
            amberMantisConnection.close();
        }
    }
}
