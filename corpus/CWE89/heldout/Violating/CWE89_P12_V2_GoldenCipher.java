import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenCipher {
    private static boolean privateTrue = true;

    public void runGoldenCipher() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("GOLDEN_CIPHER_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenCipherBase baseObject = new CWE89_P12_V2_GoldenCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenCipherBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenCipherSink extends CWE89_P12_V2_GoldenCipherBase {
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
