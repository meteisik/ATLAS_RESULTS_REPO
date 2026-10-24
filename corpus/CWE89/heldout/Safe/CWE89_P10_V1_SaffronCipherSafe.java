import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronCipherSafe {

    public static String data;

    public void runSaffronCipher() throws SQLException {
        data = "foo";
        (new CWE89_P10_V1_SaffronCipherSafeSink()).querySaffronCipher();
    }
}

class CWE89_P10_V1_SaffronCipherSafeSink {
    public void querySaffronCipher() throws SQLException {
        String data = CWE89_P10_V1_SaffronCipherSafe.data;
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        Statement saffronCipherStatement = null;
        ResultSet saffronCipherRows = null;
        try {
            saffronCipherStatement = saffronCipherConnection.createStatement();
            saffronCipherRows = saffronCipherStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronCipherRows.getRow());
        } finally {
            if (saffronCipherRows != null) {
                saffronCipherRows.close();
            }
            if (saffronCipherStatement != null) {
                saffronCipherStatement.close();
            }
            saffronCipherConnection.close();
        }
    }
}
