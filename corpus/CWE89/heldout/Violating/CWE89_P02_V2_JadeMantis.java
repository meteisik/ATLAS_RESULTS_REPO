import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeMantis {
    private static boolean privateTrue = true;

    public void runJadeMantis() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("JADE_MANTIS_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection jadeMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeMantis");
            Statement jadeMantisStatement = null;
            ResultSet jadeMantisRows = null;
            try {
                jadeMantisStatement = jadeMantisConnection.createStatement();
                jadeMantisRows = jadeMantisStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(jadeMantisRows.getRow());
            } finally {
                if (jadeMantisRows != null) {
                    jadeMantisRows.close();
                }
                if (jadeMantisStatement != null) {
                    jadeMantisStatement.close();
                }
                jadeMantisConnection.close();
            }
        }
    }
}
