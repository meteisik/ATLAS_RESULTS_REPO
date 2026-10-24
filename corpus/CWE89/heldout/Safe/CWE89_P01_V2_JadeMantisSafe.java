import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_JadeMantisSafe {

    public void runJadeMantis() throws SQLException {
        String data;
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
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
