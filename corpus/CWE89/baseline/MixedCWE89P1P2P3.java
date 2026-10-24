package cwe89.mixed;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class MixedCWE89P1P2P3 {

    // Violation 1 (P01, Juliet _01): an environment value is read and
    // concatenated into the executeQuery SQL string in the same method.
    public void inlineLookup() throws SQLException {
        String data;
        data = System.getenv("INLINE_FILTER");
        Connection inlineConnection = DriverManager.getConnection("jdbc:hsqldb:mem:inline");
        Statement inlineStatement = null;
        ResultSet inlineRows = null;
        try {
            inlineStatement = inlineConnection.createStatement();
            inlineRows = inlineStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(inlineRows.getRow());
        } finally {
            if (inlineRows != null) {
                inlineRows.close();
            }
            if (inlineStatement != null) {
                inlineStatement.close();
            }
            inlineConnection.close();
        }
    }

    // Violation 2 (P02, Juliet _31): the environment value is copied to a
    // second local inside a nested block; a later block re-reads the copy and
    // concatenates it into the executeQuery SQL string.
    public void copiedLookup() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("COPIED_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection copiedConnection = DriverManager.getConnection("jdbc:hsqldb:mem:copied");
            Statement copiedStatement = null;
            ResultSet copiedRows = null;
            try {
                copiedStatement = copiedConnection.createStatement();
                copiedRows = copiedStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(copiedRows.getRow());
            } finally {
                if (copiedRows != null) {
                    copiedRows.close();
                }
                if (copiedStatement != null) {
                    copiedStatement.close();
                }
                copiedConnection.close();
            }
        }
    }

    // Violation 3 (P03, Juliet _41): the environment value is passed as an
    // argument to a private sink method of the same class.
    private void helperQuery(String data) throws SQLException {
        Connection helperConnection = DriverManager.getConnection("jdbc:hsqldb:mem:helper");
        Statement helperStatement = null;
        ResultSet helperRows = null;
        try {
            helperStatement = helperConnection.createStatement();
            helperRows = helperStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(helperRows.getRow());
        } finally {
            if (helperRows != null) {
                helperRows.close();
            }
            if (helperStatement != null) {
                helperStatement.close();
            }
            helperConnection.close();
        }
    }

    public void helperLookup() throws SQLException {
        String data;
        data = System.getenv("HELPER_FILTER");
        helperQuery(data);
    }

    // Safe (P01 safe twin, Juliet _01 goodG2B): the SQL string is built from
    // the constant "foo", so no environment value reaches executeQuery.
    public void constantLookup() throws SQLException {
        String data;
        data = "foo";
        Connection constantConnection = DriverManager.getConnection("jdbc:hsqldb:mem:constant");
        Statement constantStatement = null;
        ResultSet constantRows = null;
        try {
            constantStatement = constantConnection.createStatement();
            constantRows = constantStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(constantRows.getRow());
        } finally {
            if (constantRows != null) {
                constantRows.close();
            }
            if (constantStatement != null) {
                constantStatement.close();
            }
            constantConnection.close();
        }
    }
}
