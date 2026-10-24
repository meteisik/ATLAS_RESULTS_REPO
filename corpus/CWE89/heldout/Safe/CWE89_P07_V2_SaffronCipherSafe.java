import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronCipherSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runSaffronCipher() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = (new CWE89_P07_V2_SaffronCipherSafeSource()).loadSaffronCipher();
        } else {
            data = null;
        }
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

class CWE89_P07_V2_SaffronCipherSafeSource {
    public String loadSaffronCipher() {
        String data;
        data = "foo";
        return data;
    }
}
