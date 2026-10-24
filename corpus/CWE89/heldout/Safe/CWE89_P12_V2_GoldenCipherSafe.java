import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenCipherSafe {
    private static boolean privateTrue = true;

    public void runGoldenCipher() throws SQLException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenCipherSafeBase baseObject = new CWE89_P12_V2_GoldenCipherSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenCipherSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenCipherSafeSink extends CWE89_P12_V2_GoldenCipherSafeBase {
    public void action(String data) throws SQLException {
        Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
        Statement goldenCipherStatement = null;
        ResultSet goldenCipherRows = null;
        try {
            goldenCipherStatement = goldenCipherConnection.createStatement();
            goldenCipherRows = goldenCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenCipherRows.getRow());
        } finally {
            if (goldenCipherRows != null) {
                goldenCipherRows.close();
            }
            if (goldenCipherStatement != null) {
                goldenCipherStatement.close();
            }
            goldenCipherConnection.close();
        }
    }
}
